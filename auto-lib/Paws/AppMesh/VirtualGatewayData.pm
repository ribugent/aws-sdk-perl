# Generated by default/object.tt
package Paws::AppMesh::VirtualGatewayData;
  use Moose;
  has MeshName => (is => 'ro', isa => 'Str', request_name => 'meshName', traits => ['NameInRequest'], required => 1);
  has Metadata => (is => 'ro', isa => 'Paws::AppMesh::ResourceMetadata', request_name => 'metadata', traits => ['NameInRequest'], required => 1);
  has Spec => (is => 'ro', isa => 'Paws::AppMesh::VirtualGatewaySpec', request_name => 'spec', traits => ['NameInRequest'], required => 1);
  has Status => (is => 'ro', isa => 'Paws::AppMesh::VirtualGatewayStatus', request_name => 'status', traits => ['NameInRequest'], required => 1);
  has VirtualGatewayName => (is => 'ro', isa => 'Str', request_name => 'virtualGatewayName', traits => ['NameInRequest'], required => 1);

1;

### main pod documentation begin ###

=head1 NAME

Paws::AppMesh::VirtualGatewayData

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::AppMesh::VirtualGatewayData object:

  $service_obj->Method(Att1 => { MeshName => $value, ..., VirtualGatewayName => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::AppMesh::VirtualGatewayData object:

  $result = $service_obj->Method(...);
  $result->Att1->MeshName

=head1 DESCRIPTION

An object that represents a virtual gateway returned by a describe
operation.

=head1 ATTRIBUTES


=head2 B<REQUIRED> MeshName => Str

The name of the service mesh that the virtual gateway resides in.


=head2 B<REQUIRED> Metadata => L<Paws::AppMesh::ResourceMetadata>




=head2 B<REQUIRED> Spec => L<Paws::AppMesh::VirtualGatewaySpec>

The specifications of the virtual gateway.


=head2 B<REQUIRED> Status => L<Paws::AppMesh::VirtualGatewayStatus>

The current status of the virtual gateway.


=head2 B<REQUIRED> VirtualGatewayName => Str

The name of the virtual gateway.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::AppMesh>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

