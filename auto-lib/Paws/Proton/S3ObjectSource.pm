# Generated by default/object.tt
package Paws::Proton::S3ObjectSource;
  use Moose;
  has Bucket => (is => 'ro', isa => 'Str', request_name => 'bucket', traits => ['NameInRequest'], required => 1);
  has Key => (is => 'ro', isa => 'Str', request_name => 'key', traits => ['NameInRequest'], required => 1);

1;

### main pod documentation begin ###

=head1 NAME

Paws::Proton::S3ObjectSource

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::Proton::S3ObjectSource object:

  $service_obj->Method(Att1 => { Bucket => $value, ..., Key => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::Proton::S3ObjectSource object:

  $result = $service_obj->Method(...);
  $result->Att1->Bucket

=head1 DESCRIPTION

Template bundle S3 bucket data.

=head1 ATTRIBUTES


=head2 B<REQUIRED> Bucket => Str

The name of the S3 bucket that contains a template bundle.


=head2 B<REQUIRED> Key => Str

The path to the S3 bucket that contains a template bundle.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::Proton>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

