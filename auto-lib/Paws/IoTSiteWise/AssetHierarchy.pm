# Generated by default/object.tt
package Paws::IoTSiteWise::AssetHierarchy;
  use Moose;
  has Id => (is => 'ro', isa => 'Str', request_name => 'id', traits => ['NameInRequest']);
  has Name => (is => 'ro', isa => 'Str', request_name => 'name', traits => ['NameInRequest'], required => 1);

1;

### main pod documentation begin ###

=head1 NAME

Paws::IoTSiteWise::AssetHierarchy

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::IoTSiteWise::AssetHierarchy object:

  $service_obj->Method(Att1 => { Id => $value, ..., Name => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::IoTSiteWise::AssetHierarchy object:

  $result = $service_obj->Method(...);
  $result->Att1->Id

=head1 DESCRIPTION

Describes an asset hierarchy that contains a hierarchy's name and ID.

=head1 ATTRIBUTES


=head2 Id => Str

The ID of the hierarchy. This ID is a C<hierarchyId>.


=head2 B<REQUIRED> Name => Str

The hierarchy name provided in the CreateAssetModel
(https://docs.aws.amazon.com/iot-sitewise/latest/APIReference/API_CreateAssetModel.html)
or UpdateAssetModel
(https://docs.aws.amazon.com/iot-sitewise/latest/APIReference/API_UpdateAssetModel.html)
API operation.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::IoTSiteWise>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

